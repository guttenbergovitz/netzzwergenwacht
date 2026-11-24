# Changelog

All notable changes to NetzZwergenWacht are documented in this file.

## [Unreleased] - `rewrite/rust`

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
