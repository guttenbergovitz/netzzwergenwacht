# Implementation Roadmap

NetzZwergenWacht is being rewritten in Rust on `rewrite/rust` using incremental vertical slices.

## Phase 0: Discovery and Documentation *(Current)*
- [x] Audit Python implementation on `main` and verify capability gaps
- [x] Create `rewrite/rust` branch preserving Python on `main`
- [x] Write ADR 0001 (`docs/adr/0001-rewrite-netzzwergenwacht-in-rust.md`)
- [x] Document capability inventory, rewrite strategy, and target architecture (`docs/architecture/*`)
- [x] Initialise minimal Cargo project (`Cargo.toml`, `src/lib.rs`, `src/main.rs`) with `fmt`, `clippy`, and `test` gates
- [x] Configure CI quality gates (`.github/workflows/ci.yml`)

## Phase 1: Minimal Deterministic Core
- [ ] Implement validated `AuditTarget` (with scheme/host checks and private-IP guardrails)
- [ ] Implement bounded HTTP + `rustls` TLS collector (`reqwest`)
- [ ] Implement `EvidenceSnapshot` and normalised `Finding` / `Measurement` contracts
- [ ] Implement initial deterministic rules (HTTP reliability, security headers, TLS validity, basic HTML/SEO meta)
- [ ] Provide `nzw check` CLI and versioned JSON output (`schemars`)
- [ ] Add offline HTTP mock fixture tests and contract tests
- [ ] Remove legacy Python code from `rewrite/rust` once Phase 1 vertical slice is verified

## Phase 2: Browser and Analysis Capabilities
- [ ] Evaluate and integrate controlled headless Chromium automation
- [ ] Implement Lighthouse adapter (performance / Core Web Vitals) with version provenance
- [ ] Implement axe-core adapter (accessibility checks) with version provenance
- [ ] Implement remaining deterministic analysers (`InhaltZwerg`, `VisualZwerg`, full `SEOZwerg`)
- [ ] Validate all analysers against controlled offline HTML/DOM fixtures

## Phase 3: Persistence and Regression Analysis
- [ ] Persist `AuditReport` and `EvidenceSnapshot` summaries as JSONL
- [ ] Implement stable `FindingFingerprint` generation
- [ ] Add `nzw diff` / regression comparison (`New`, `Persisting`, `Resolved`)
- [ ] Support batch auditing and configurable policy quality gates (exit codes for CI)

## Phase 4: Optional Intelligence
- [ ] Run focused technical spike for `rig-core`
- [ ] Implement provider-independent optional LLM synthesis behind `ExecutionBudget` token/cost caps
- [ ] Add cross-domain finding correlation and structured remediation recommendations
- [ ] Enforce untrusted-data / prompt-injection boundaries and evaluation tests

## Phase 5: Production Hardening
- [ ] Benchmark memory, CPU, and concurrency behaviour under load
- [ ] Chaos/cancellation tests for partial failures and timeouts
- [ ] Finalise `tracing` / OpenTelemetry observability and `cargo-audit` checks
- [ ] Establish release packaging and distribution
