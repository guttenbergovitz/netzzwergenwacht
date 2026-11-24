# NetzZwergenWacht

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **An evidence-driven external web quality and reliability auditing engine with optional AI-assisted analysis.**

NetzZwergenWacht (NZW) is currently undergoing an architectural reorientation and **rewrite in Rust** on the `rewrite/rust` branch.

- **Reference Python Prototype**: Preserved on the `main` branch as a historical reference and source of functional requirements.
- **Architectural Decision**: See [ADR 0001: Rewrite NetzZwergenWacht in Rust](docs/adr/0001-rewrite-netzzwergenwacht-in-rust.md).

## Current Status (`Phase 0`)

- **Implemented**:
  - Architecture Decision Record, capability inventory, target architecture specs, and incremental roadmap (`docs/`).
  - Minimal Rust crate skeleton (`Cargo.toml`, `src/lib.rs`, `src/main.rs`) with domain foundation types and unit tests.
  - CI quality gates (`cargo fmt`, `cargo clippy`, `cargo test`).
- **Planned (Phase 1+)**:
  - Bounded HTTP + `rustls` collection engine and `EvidenceSnapshot` capture.
  - Deterministic Zwerg analysers, browser/Lighthouse/axe-core adapters, JSONL persistence, and optional Rig-based AI synthesis.

See [docs/roadmap.md](docs/roadmap.md) for the full vertical-slice delivery plan.

## Architecture Documentation

- [Architecture Overview](docs/architecture/overview.md)
- [Domain Model](docs/architecture/domain-model.md)
- [Collection Engine](docs/architecture/collection-engine.md)
- [Analysis Engine](docs/architecture/analysis-engine.md)
- [Evidence Model](docs/architecture/evidence-model.md)
- [Intelligence Layer](docs/architecture/intelligence-layer.md)
- [Execution & Resource Model](docs/architecture/execution-and-resource-model.md)
- [Security Model](docs/architecture/security-model.md)
- [Python Capability Inventory](docs/migration/python-capability-inventory.md)
- [Rewrite Strategy](docs/migration/rewrite-strategy.md)

## Development (Rust)

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

MIT — see [LICENSE](LICENSE).
