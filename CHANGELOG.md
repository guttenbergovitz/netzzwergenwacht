# Changelog

All notable changes to NetzZwergenWacht are documented in this file.

## [Unreleased] - `rewrite/rust`

### Phase 0: Architectural Reorientation & Rust Project Initialisation (2026-11-24)
- Created `rewrite/rust` branch preserving the Python reference implementation on `main`.
- Added ADR 0001 (`docs/adr/0001-rewrite-netzzwergenwacht-in-rust.md`).
- Audited Python codebase and documented capability inventory (`docs/migration/python-capability-inventory.md`) and rewrite strategy (`docs/migration/rewrite-strategy.md`).
- Documented target architecture (`docs/architecture/*.md`) and incremental roadmap (`docs/roadmap.md`).
- Added `LICENSE` (MIT), `AGENTS.md`, and `CHANGELOG.md`.
- Initialised minimal Rust Cargo workspace/crate (`Cargo.toml`, `src/lib.rs`, `src/main.rs`) and CI quality gates (`.github/workflows/ci.yml`).

## [0.1.0-python] - `main`

- Experimental Python prototype implementing seven Zwerg analysers, Typer/Rich CLI, OpenAI/CrewAI integration, and PDF/JSON reporting. Preserved on `main` as historical reference.
