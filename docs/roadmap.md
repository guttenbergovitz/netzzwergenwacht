# Capability-Driven Implementation Roadmap

Status legend:
- **Implemented**: Code exists on `develop` / `rewrite/rust`.
- **Tested**: Covered by automated unit/integration tests.
- **Experimentally demonstrated**: End-to-end flow demonstrated with controlled/mock inputs.
- **Operationally validated**: Verified against real target applications and benchmarks.
- **Planned** / **Blocked**: Not yet built or awaiting dependency/prerequisite.

---

## Milestone A: Foundation Integrity *(In Progress)*
- **Validated `AuditTarget` & SSRF guardrails** (`src/domain.rs`): *Implemented, Tested*
- **Bounded HTTP + `rustls` TLS collector** (`src/collection.rs`): *Implemented, Tested*
- **Shared single-parse `DocumentObservations` & 9 deterministic analysers** (`src/analysis/`): *Implemented, Tested*
- **Level 2 subprocess adapters** (`lighthouse`, `chromium` CDP, `axe-core` in `src/adapters/`): *Implemented (CLI parsers Tested; live browser integration Planned)*
- **Chaos & cancellation integration tests** (`tests/chaos_and_cancellation.rs`): *Implemented, Tested*
- **Defect register remediation** (`docs/evaluation/defect-register.md` items #1–#10): *Planned* (required before declaring Milestone A complete)

## Milestone B: Agentic Investigation Proof of Concept *(In Progress)*
- [x] **ADR 0005 & Rig (`rig-core`) evaluation** (`docs/adr/0005-agentic-investigation-architecture.md`): *Implemented*
- [x] **Investigation domain model & `InvestigationContext`** (`src/investigation/mod.rs`): *Implemented, Tested*
- [x] **Rig `PortableTool` catalogue & multi-turn `KommandantZwerg` hypothesis loop** (`src/investigation/tools.rs`, `src/investigation/mod.rs`, `nzw investigate`): *Implemented, Experimentally demonstrated (mock LLM + backend)*
- [x] **`rig-core` (`0.42.0`) crate integration**: *Implemented, Tested* (MSRV `1.88`-compatible `PortableTool` + `ToolDefinition`)
- [x] **Initial `ExecutiveBrief` & backlog-ready `RemediationTask`s** (`src/investigation/mod.rs`): *Implemented, Tested*

## Milestone C: Application-Level Investigation *(In Progress)*
- [x] **Bounded crawling, URL normalisation, and origin/depth caps** (`src/discovery/mod.rs`): *Implemented, Tested*
- [x] **Page type classification (`PageType`)** (`src/discovery/mod.rs`): *Implemented, Tested*
- [x] **Systemic issue clustering across pages (`SystemicIssue`)** (`src/discovery/mod.rs`): *Implemented, Tested*
- [x] **Adaptive sampling & crawl tool wired into `KommandantZwerg`** (`src/investigation/tools.rs`, `CrawlAndClusterTool`): *Implemented, Tested*

## Milestone D: Stakeholder Value *(In Progress)*
- [x] **Executive brief (`ExecutiveBrief`) & backlog-ready `RemediationTask`s** (`src/investigation/reporting.rs`): *Implemented, Tested*
- [x] **Configurable release readiness assessments (`ReleaseReadinessAssessment`)** (`src/investigation/reporting.rs`): *Implemented, Tested*
- [x] **Role-tailored report perspectives & Markdown export (`--audience pm|po|cto|technical`, `--format markdown`)**: *Implemented, Tested*

## Milestone E: Continuous Quality Assurance *(In Progress)*
- [x] **Comparable regression semantics (`unverified_findings`, `changed_findings`, `not_comparable_reason`)** (`src/persistence.rs`): *Implemented, Tested*
- [x] **`nzw verify --baseline <path> <url>` remediation verification**: *Implemented, Tested via Zwergenprüfstand*
- [ ] **Multi-run `reintroduced` tracking, quality baselines, and portfolio comparisons**: *Planned*

## Milestone F: Product Hardening & Integration *(In Progress)*
- [x] **`Zwergenprüfstand` benchmark fixtures & Mode A vs Mode C evaluation** (`fixtures/zwergenpruefstand/`, `tests/zwergenpruefstand_eval.rs`): *Implemented, Experimentally demonstrated (local HTTP server + scripted LLM)*
- [ ] **Live external LLM & real-browser operational benchmarks**: *Planned / Blocked on external API keys in CI*
- [ ] **Optional MCP interface & external issue-tracker integrations**: *Planned*
