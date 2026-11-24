# Implementation Roadmap

NetzZwergenWacht is being rewritten in Rust on `rewrite/rust` using incremental vertical slices.

## Phase 0: Discovery and Documentation *(Completed)*
- [x] Audit Python implementation on `main` and move frozen reference into `./legacy/`
- [x] Create `rewrite/rust` branch preserving Python on `main`
- [x] Write ADR 0001 and ADR 0002 (`docs/adr/`)
- [x] Document capability inventory, rewrite strategy, conventions, Zwergenbrigade, and target architecture (`docs/`)
- [x] Initialise Cargo project with strict lints (`clippy.toml`, `rustfmt.toml`, `Taskfile.yml`, `.github/workflows/ci.yml`)

## Phase 1: Minimal Deterministic Core *(Completed)*
- [x] Implement validated `AuditTarget` (with SSRF/IP guardrails and deserialisation validation)
- [x] Implement bounded HTTP collector (`reqwest` + `rustls`, `.no_proxy()`, DNS pinning, redirect hop validation, end-to-end `audit_timeout`, streaming `max_response_bytes`)
- [x] Implement `ZWERGENBRIGADE` registry (`src/brigade.rs`) and `EvidenceLevel` (`Source` / `Rendered` / `Behavioural`)
- [x] Implement shared `DocumentObservations` single-parse HTML5 model (`analysis::document`)
- [x] Implement initial deterministic Zwerge: `NetzZwerg`, `SicherheitsZwerg`, `LeistungsZwerg` (HTTP), `StrukturZwerg`, `ZugänglichkeitsZwerg` (Source), `SuchZwerg`, `InhaltsZwerg`
- [x] Provide `nzw check` / `nzw validate` CLI (`DokumentationsZwerg` plain-text + versioned JSON output + exit codes `0`/`1`/`2`)
- [x] Add `rustls` TLS peer certificate metadata extraction (`x509-parser`) to `CollectionEngine` and `SicherheitsZwerg`
- [x] Add `schemars` JSON schema generation and contract tests (`tests/schema_contract.rs`)

## Phase 2: Browser and Analysis Capabilities *(Completed)*
- [x] Integrate controlled headless Chromium CDP subprocess collector (`BrowserEvidence`, `--browser`)
- [x] Implement Lighthouse subprocess adapter (`LeistungsZwerg` Level 2 metrics, `--lighthouse`) with version provenance
- [x] Implement `axe-core` subprocess adapter (`ZugänglichkeitsZwerg` Level 2 `AxeEvidence`, `--axe`) with version provenance
- [x] Implement `BrowserZwerg` (`analysis::browser`) and `GestaltungsZwerg` (`analysis::visual`) deterministic Level 2 analysers
- [x] Validate all Level 2 analysers and adapter parsers against controlled offline JSON/struct fixtures

## Phase 3: Persistence and Regression Analysis *(Completed)*
- [x] Persist `AuditReport` entries as JSONL (`src/persistence.rs`, `nzw check --history`)
- [x] Implement stable `FindingFingerprint` generation (FNV-1a 64-bit over host, rule, and evidence)
- [x] Add `nzw diff` regression comparison (`New`, `Persisting`, `Resolved`)
- [x] Support batch auditing (`nzw batch`) and TOML configuration / policy quality gates (`src/config.rs`, `--config`, `--fail-on`)

## Phase 4: Optional Intelligence (`KommandantZwerg`) *(Completed)*
- [x] Implement provider-independent `LlmProvider` trait and `OpenAiCompatibleProvider` (`src/intelligence/mod.rs`, opt-in `--ai`)
- [x] Enforce `LlmBudget` (`max_tokens`, `max_requests`, `timeout`) and `FindingKind::AiInterpretation` tagging
- [x] Add cross-domain finding correlation and prioritised remediation synthesis
- [x] Enforce untrusted-data / prompt-injection delimiter boundaries (`<untrusted_audit_evidence>`) and offline mock tests

## Phase 5: Production Hardening *(Completed)*
- [x] Chaos/cancellation integration tests for stalled servers, mid-stream drops, and future cancellation (`tests/chaos_and_cancellation.rs`)
- [x] `tracing` / `tracing-subscriber` structured observability (`RUST_LOG` on `stderr`)
- [x] `cargo-audit` CI check (`.github/workflows/ci.yml`, `Taskfile.yml`)
- [x] Release profile (`lto = "thin"`, `strip = "symbols"`) and tag-based release packaging workflow (`.github/workflows/release.yml`)
