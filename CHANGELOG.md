# Changelog

All notable changes to NetzZwergenWacht are documented in this file.

## [Unreleased] - `develop`

### Crawl Tool Integration & Remediation Verification (`nzw verify`) (2026-11-24)
- Added `CrawlAndClusterTool` (`crawl_and_cluster_site`) as a `rig-core` `PortableTool` in `src/investigation/tools.rs`, surfacing `discovered_pages` and `systemic_issues` in `InvestigationReport` and `ExecutiveBrief`.
- Added `nzw verify --baseline <path> <url>` CLI subcommand in `src/main.rs` distinguishing `resolved`, `persisting`, `unverified`, and `new` findings.

### Adaptive Crawling & Systemic Issue Clustering (Milestone C) (2026-11-24)
- Added `src/discovery/mod.rs` (`CrawlBudget`, `DiscoveredPage`, `PageType`, `PageCrawlStatus`, `SystemicIssue`, `discover_same_origin_links`, `classify_page`, `cluster_systemic_issues`, `crawl_and_cluster`).
- Extended `DocumentObservations` (`src/analysis/document.rs`) to capture `link_hrefs` in the single HTML5 pass.

### Milestone A Foundation Defect Fixes (2026-11-24)
- Fixed false historical resolutions in `persistence::diff_reports` by classifying skipped/unavailable baseline rules as `unverified_findings`.
- Capped external adapter stdout/stderr buffers at 16 MiB in `adapters::run_bounded_command`.
- Redacted `api_key` in `OpenAiCompatibleProvider`'s `Debug` impl, stream-capped LLM HTTP responses at 1 MiB, validated `related_rules`, and removed mid-JSON prompt truncation in `src/intelligence/mod.rs`.
- Marked `CollectorOutcome::Skipped` HTTP outcomes as policy violations in `config::evaluate_policy`.

### Multi-Turn Investigation Hardening, `rig-core` Integration & Stakeholder Briefs (2026-11-24)
- Integrated `rig-core` (`0.42.0`, MSRV `1.88`) with typed `PortableTool` implementations (`InspectBrowserRuntimeTool`, `InspectRenderedAccessibilityTool`) in `src/investigation/tools.rs`.
- Fixed P0/P1 defects in `src/investigation/mod.rs`: deterministic `Inconclusive` enforcement when follow-up tools fail, `analyse_axe_only` avoiding empty-HTML re-analysis, remaining wall-clock budget propagation, unique `InvestigationId` generation, rule-ID verification, split `supporting_evidence`/`contradictory_evidence`, and full `snapshot` preservation.
- Upgraded `run_investigation` to a bounded multi-turn loop and added `ExecutiveBrief` + `RemediationTask` outputs on `InvestigationReport`.

### Agentic Investigation Proof of Concept (Milestone B) (2026-11-24)
- Added `src/investigation/mod.rs` (`InvestigationContext`, `InvestigationBudget`, `BudgetLedger`, `DiagnosticHypothesis`, `LiveDiagnosticBackend`, `run_investigation`) implementing the `KommandantZwerg` hypothesis-driven diagnostic loop.
- Added `nzw investigate <url> [--objective ...]` CLI subcommand in `src/main.rs`.

### Strategic Reorientation & Defect Reconciliation (2026-11-24)
- Added [docs/migration/original-agentic-vision.md](docs/migration/original-agentic-vision.md) recovering `./legacy` product intent and agentic lessons.
- Added [docs/product/vision-and-strategy.md](docs/product/vision-and-strategy.md) and [docs/product/competitive-landscape.md](docs/product/competitive-landscape.md).
- Added [docs/evaluation/defect-register.md](docs/evaluation/defect-register.md) verifying 14 concrete defects/risks against the current Rust codebase.
- Added [ADR 0005](docs/adr/0005-agentic-investigation-architecture.md) (amending ADR 0004) with `rig-core` evaluation and the hierarchical hypothesis-driven investigation architecture.
- Replaced phase-complete roadmap with capability-driven Milestones A–F in [docs/roadmap.md](docs/roadmap.md).

### Phase 5: Production Hardening (2026-11-24)
- Added structured `tracing` and `tracing-subscriber` (`RUST_LOG` on `stderr`) across CLI, HTTP collection, and bounded adapters.
- Added chaos and cancellation integration tests (`tests/chaos_and_cancellation.rs`) covering stalled servers, mid-stream drops, and future cancellation.
- Added `cargo-audit` CI job (`.github/workflows/ci.yml`), `task audit` (`Taskfile.yml`), `[profile.release]` (`lto = "thin"`, `strip = "symbols"`), and tag-triggered release packaging (`.github/workflows/release.yml`).

### Phase 4: Optional Intelligence (`KommandantZwerg`) (2026-11-24)
- Added ADR 0004 (`docs/adr/0004-optional-intelligence-kommandant.md`) for provider-independent optional AI synthesis.
- Added `src/intelligence/mod.rs` (`LlmProvider`, `OpenAiCompatibleProvider`, `LlmBudget`, `build_sanitised_prompt`, `synthesise`) with prompt-injection delimiters and `FindingKind::AiInterpretation` tagging.
- Added opt-in `--ai` flag to `nzw check` and marked `DwarfId::Kommandant` as `ImplementationStatus::Implemented`.

### Phase 2: Level 2 Analysers & Subprocess Adapters (2026-11-24)
- Added ADR 0003 (`docs/adr/0003-browser-and-external-tool-adapters.md`) for bounded subprocess adapters and opt-in Level 2 collection.
- Added `EvidenceSnapshot` Level 2 fields (`browser`, `lighthouse`, `axe`) with `#[serde(default)]` backward compatibility.
- Added bounded Lighthouse, headless Chromium CDP, and `axe-core` subprocess adapters (`src/adapters/`) with opt-in `nzw check --lighthouse`, `--browser`, and `--axe` CLI flags.
- Implemented `BrowserZwerg` (`analysis::browser`) and `GestaltungsZwerg` (`analysis::visual`), plus Level 2 Core Web Vitals in `LeistungsZwerg` and `axe-core` evaluation in `ZugänglichkeitsZwerg`.

### Phase 3: Persistence & Regression Analysis (2026-11-24)
- Added TOML configuration (`AppConfig`, `BudgetConfig`, `PolicyConfig`) and `evaluate_policy` quality gates (`src/config.rs`, `--config`, `--fail-on`).
- Added bounded concurrent batch auditing (`collection::collect_batch` with Tokio `Semaphore` + `nzw batch <targets_file>`).
- Added deterministic `FindingFingerprint` (`domain.rs`) populated automatically for every emitted finding in `analysis::run_all`.
- Added JSONL audit history persistence and `diff_reports` regression classification (`src/persistence.rs`).
- Added `--history <path>` to `nzw check` and `nzw diff <baseline> <current>` CLI subcommand.

### Phase 1: Zwergenbrigade, Shared Document Model & Core Hardening (2026-11-24)
- Added TLS peer certificate extraction (`reqwest::tls::TlsInfo` + `x509-parser`) and `sec.tls.certificate_expiry` check in `SicherheitsZwerg`.
- Added `InhaltsZwerg` (`analysis::content`) consuming shared `DocumentObservations` visible text statistics.
- Added `schemars` `JsonSchema` derives and `tests/schema_contract.rs` integration contract test.
- Added ADR 0002 (`docs/adr/0002-zwergenbrigade-domains-shared-document-and-evidence-levels.md`), `docs/architecture/zwergenbrigade.md`, and `docs/architecture/document-analysis.md`.
- Added central `ZWERGENBRIGADE` registry (`src/brigade.rs`) separating German dwarf identities from `en-GB` ASCII technical modules.
- Hardened `AuditTarget` deserialisation, `MeasurementUnit` enum, `EvidenceLevel` (`Source`/`Rendered`/`Behavioural`), `EvidenceSource`, `.no_proxy()` DNS-pinning protection, end-to-end `audit_timeout`, truncated-body skip guardrails, semantic security-header validation, and CLI exit codes (`0`/`1`/`2`).
- Added single-parse `DocumentObservations` (`analysis::document`).
- Implemented `NetzZwerg`, `SicherheitsZwerg`, `LeistungsZwerg` (HTTP), `StrukturZwerg`, `ZugänglichkeitsZwerg` (Source), `SuchZwerg`, and `DokumentationsZwerg` CLI presentation.

### Phase 0: Architectural Reorientation & Rust Project Initialisation (2026-11-24)
- Created `rewrite/rust` branch preserving the Python prototype on `main` and in `legacy/`.
- Added ADR 0001, capability inventory, rewrite strategy, target architecture specs, roadmap, `LICENSE` (MIT), `AGENTS.md`, `docs/conventions.md`, `Taskfile.yml`, and CI quality gates.

## [0.1.0-python] - `main`

- Experimental Python prototype implementing seven Zwerg analysers, Typer/Rich CLI, OpenAI/CrewAI integration, and PDF/JSON reporting. Preserved on `main` as historical reference.
