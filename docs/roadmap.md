# Implementation Roadmap

NetzZwergenWacht is being rewritten in Rust on `rewrite/rust` using incremental vertical slices.

## Phase 0: Discovery and Documentation *(Completed)*
- [x] Audit Python implementation on `main` and move frozen reference into `./legacy/`
- [x] Create `rewrite/rust` branch preserving Python on `main`
- [x] Write ADR 0001 and ADR 0002 (`docs/adr/`)
- [x] Document capability inventory, rewrite strategy, conventions, Zwergenbrigade, and target architecture (`docs/`)
- [x] Initialise Cargo project with strict lints (`clippy.toml`, `rustfmt.toml`, `Taskfile.yml`, `.github/workflows/ci.yml`)

## Phase 1: Minimal Deterministic Core *(Current — Slices 1.1–1.5 Implemented)*
- [x] Implement validated `AuditTarget` (with SSRF/IP guardrails and deserialisation validation)
- [x] Implement bounded HTTP collector (`reqwest` + `rustls`, `.no_proxy()`, DNS pinning, redirect hop validation, end-to-end `audit_timeout`, streaming `max_response_bytes`)
- [x] Implement `ZWERGENBRIGADE` registry (`src/brigade.rs`) and `EvidenceLevel` (`Source` / `Rendered` / `Behavioural`)
- [x] Implement shared `DocumentObservations` single-parse HTML5 model (`analysis::document`)
- [x] Implement initial deterministic Zwerge: `NetzZwerg`, `SicherheitsZwerg`, `LeistungsZwerg` (HTTP), `StrukturZwerg`, `ZugänglichkeitsZwerg` (Source), `SuchZwerg`
- [x] Provide `nzw check` / `nzw validate` CLI (`DokumentationsZwerg` plain-text + versioned JSON output + exit codes `0`/`1`/`2`)
- [ ] Add `rustls` TLS certificate metadata extraction to `CollectionEngine`
- [ ] Add `schemars` JSON schema generation and contract tests
- [ ] Implement initial `InhaltsZwerg` (content quality, readability, language)

## Phase 2: Browser and Analysis Capabilities
- [ ] Evaluate and integrate controlled headless Chromium automation (`BrowserZwerg`)
- [ ] Implement Lighthouse adapter (`LeistungsZwerg` Level 2 metrics) with version provenance
- [ ] Implement axe-core adapter (`ZugänglichkeitsZwerg` Level 2 rendered DOM checks) with version provenance
- [ ] Implement `GestaltungsZwerg` (viewport overflow, broken images, responsive screenshots)
- [ ] Validate all analysers against controlled offline HTML/DOM fixtures

## Phase 3: Persistence and Regression Analysis
- [ ] Persist `AuditReport` and `EvidenceSnapshot` summaries as JSONL
- [ ] Implement stable `FindingFingerprint` generation
- [ ] Add `nzw diff` / regression comparison (`New`, `Persisting`, `Resolved`)
- [ ] Support batch auditing and configurable policy quality gates

## Phase 4: Optional Intelligence (`KommandantZwerg`)
- [ ] Run focused technical spike for `rig-core`
- [ ] Implement provider-independent optional LLM synthesis behind `ExecutionBudget` token/cost caps
- [ ] Add cross-domain finding correlation and structured remediation recommendations
- [ ] Enforce untrusted-data / prompt-injection boundaries and evaluation tests

## Phase 5: Production Hardening
- [ ] Benchmark memory, CPU, and concurrency behaviour under load
- [ ] Chaos/cancellation tests for partial failures and timeouts
- [ ] Finalise `tracing` / OpenTelemetry observability and `cargo-audit` checks
- [ ] Establish release packaging and distribution
