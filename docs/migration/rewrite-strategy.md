# Rewrite Strategy

This document defines how NetzZwergenWacht transitions from the Python prototype on `main` to the Rust implementation on `rewrite/rust`.

## 1. Core Principle

**Translate the lessons learned, not the Python code.**

- The Python codebase on `main` remains untouched as a historical reference and source of domain requirements.
- All Rust work happens on `rewrite/rust` in vertical slices, each leaving the repository buildable, tested, and documented.
- No Python module is ported 1:1; every capability is evaluated against `docs/migration/python-capability-inventory.md`.

## 2. Branching & Removal Policy

1. `main` preserves the last cleaned Python state (`c12f9a4`).
2. `rewrite/rust` is the active development branch for the Rust rewrite.
3. Python source files (`src/netzzwergenwacht/`, `tests/`, `pyproject.toml`, `uv.lock`) are **retained on `rewrite/rust` during Phase 0** so the capability inventory and architectural specs remain directly verifiable.
4. Once Phase 1 establishes the working Rust core and CI gates, Python code may be removed from `rewrite/rust` in a dedicated commit (with `main` still preserving the Python history).
5. `rewrite/rust` will not be merged into `main` until explicitly instructed.

## 3. Vertical Slice Delivery

Rather than building all seven analysers or an AI layer up front, each phase delivers an end-to-end working slice:

1. **Phase 0 (Current)**: Repository audit, ADR 0001, capability inventory, target architecture docs, roadmap, Cargo skeleton, CI quality gates.
2. **Phase 1**: Minimal deterministic core — validated `AuditTarget`, bounded `reqwest`/`rustls` HTTP collector, `EvidenceSnapshot`, initial deterministic rules (reliability, HTTP/TLS security, basic SEO), CLI + versioned JSON output, HTTP mock fixtures.
3. **Phase 2**: Controlled browser automation + Lighthouse & axe-core adapters behind explicit contracts, remaining deterministic analysers, DOM/browser fixtures.
4. **Phase 3**: JSONL audit persistence, stable finding fingerprints, baseline comparison / regression detection, policy quality gates.
5. **Phase 4**: `rig-core` technical spike, optional AI synthesis/correlation behind token budgets and untrusted-input boundaries.
6. **Phase 5**: Resource benchmarking, cancellation/chaos testing, observability (`tracing`), security audit, release packaging.

## 4. Handling Incomplete or Unverified Features

- Placeholder, stubbed, or unverified checks must **never** emit synthetic `0` metrics or passing findings.
- Unimplemented domains or failed external tools must emit explicit `CheckStatus::Skipped` / `CheckStatus::Unavailable` / `CheckStatus::Failed` records with reason and provenance.
