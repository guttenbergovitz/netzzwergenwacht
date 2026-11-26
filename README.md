# NetzZwergenWacht

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Open-source, agentic web quality investigation system.** A brigade of specialised diagnostic agents collaboratively investigates, measures and explains the reliability, security, accessibility, performance and overall quality of web applications.
>
> **Die Zwergenbrigade** — *Kleine Zwerge. Große Sorgfalt.* (*Small dwarfs. Great diligence.*)

NetzZwergenWacht (NZW) is being redesigned and rewritten in Rust on `develop` / `rewrite/rust`. The original Python prototype is preserved on `main` and in [`legacy/`](legacy/README.md) as a frozen historical reference.

## Current Status (`Milestone A & B In Progress`)

- **Implemented**:
  - Validated `AuditTarget` with SSRF/IP guardrails (`TargetPolicy::PublicOnly` / `AllowPrivate`) and deserialisation validation.
  - Bounded HTTP + `rustls` TLS collector (`reqwest`, `.no_proxy()`, DNS pinning, redirect hop validation, end-to-end `audit_timeout`, streaming `max_response_bytes`, `x509-parser` certificate metadata).
  - Central **Die Zwergenbrigade** registry (`src/brigade.rs`) and 3-level evidence capability model (`Source`, `Rendered`, `Behavioural`).
  - Shared single-parse HTML5 `DocumentObservations` (`analysis::document`) with truncated-body guardrails.
  - Nine deterministic analysers:
    - **NetzZwerg** (`analysis::network`): HTTP status & redirect chain reliability.
    - **SicherheitsZwerg** (`analysis::security`): HTTPS, TLS certificate expiry, HSTS (`max-age > 0`), CSP, `X-Content-Type-Options`, `X-Frame-Options` / `frame-ancestors`, `Referrer-Policy`.
    - **LeistungsZwerg** (`analysis::performance`): HTTP exchange duration, payload size, compression, cache headers, and Level 2 Core Web Vitals via `--lighthouse`.
    - **StrukturZwerg** (`analysis::semantics`): duplicate IDs, heading hierarchy, landmarks, native interactive semantics.
    - **ZugänglichkeitsZwerg** (`analysis::accessibility`): source-level `<html lang>`, `img[alt]`, form labels, broken ARIA refs, accessible names, and Level 2 `axe-core` evaluation (explicitly marks Level 3 checks unavailable).
    - **SuchZwerg** (`analysis::seo`): `<title>`, meta description, canonical URL, `robots` / `X-Robots-Tag` `noindex`.
    - **InhaltsZwerg** (`analysis::content`): word count, text-to-HTML ratio, reading ease.
    - **BrowserZwerg** (`analysis::browser`): Level 2 console errors and failed subresource requests.
    - **GestaltungsZwerg** (`analysis::visual`): Level 2 viewport horizontal overflow and broken rendered images.
  - Bounded Level 2 subprocess adapters (`src/adapters/`: Lighthouse `--lighthouse`, headless Chromium CDP `--browser`, `axe-core` `--axe`).
  - **Agentic Investigation (`nzw investigate`, `nzw verify`)**: `rig-core` (`0.42.0`) `PortableTool` catalogue (`inspect_browser_runtime`, `inspect_rendered_accessibility`, `inspect_page_performance`, `inspect_document_structure`, `inspect_security_posture`, `crawl_and_cluster_site`), multi-turn `KommandantZwerg` hypothesis loop, `InvestigationScope` origin enforcement, `ExecutiveBrief`, `ReleaseReadinessAssessment`, `RemediationTask`s, and `--audience pm|po|cto|technical` Markdown/JSON reports.
  - **Zwergenprüfstand** (`fixtures/zwergenpruefstand/`, `tests/zwergenpruefstand_eval.rs`): Controlled benchmark fixtures and comparative Mode A vs Mode C evaluation suite.
  - **Zwergenleitstand TUI (`nzw tui`, `--tui`)**: Ratatui + Crossterm interactive investigation workbench with nine keyboard-driven views (`1:Overview`, `2:Brigade`, `3:Targets`, `4:Findings`, `5:Evidence`, `6:Investigation`, `7:Topology`, `8:History`, `9:System`), live `DiagnosticEvent` streaming over bounded channels, offline Evidence Query Engine exploration, terminal escape/BiDi sanitisation, and `StandardDark` / `HighContrast` / `Monochrome` (`--monochrome`, `--ascii`) themes.
  - **DokumentationsZwerg** CLI (`nzw check`, `nzw batch`, `nzw diff`, `nzw validate`, `nzw report`, `nzw tui`) with plain-text, Markdown, versioned JSON output, and interactive TUI mode (`--tui`), TOML config/policy gates (`--config`, `--fail-on`), JSONL history (`--history`), `tracing` diagnostics (`RUST_LOG`), and exit codes (`0` clean, `1` findings/partial, `2` input/collection failure).
  - Production hardening: chaos/cancellation integration tests (`tests/chaos_and_cancellation.rs`), `cargo-audit` CI check, LTO-optimised release profile, and automated tag release packaging (`.github/workflows/release.yml`).

See [docs/roadmap.md](docs/roadmap.md) for the full roadmap.

## Usage

```bash
# Run deterministic audit (text output)
cargo run --locked -- check https://example.org

# Run deterministic audit (versioned JSON output)
cargo run --locked -- check https://example.org --format json

# Validate target URL and SSRF policy without fetching
cargo run --locked -- validate https://example.org

# Launch Zwergenleitstand interactive TUI workbench
cargo run --locked -- tui
cargo run --locked -- tui https://example.org --level2
cargo run --locked -- tui --report report.json
cargo run --locked -- tui --history history.jsonl
cargo run --locked -- check https://example.org --tui
```

## Quality Gates

```bash
task check
# or:
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
cargo test --all-targets --locked
```

## Documentation

- **[Configuration Guide](CONFIG.md)** — Model routing, provider setup, cost optimization strategies
- [ADR 0001: Rewrite NetzZwergenWacht in Rust](docs/adr/0001-rewrite-netzzwergenwacht-in-rust.md)
- [ADR 0002: Zwergenbrigade Domains, Shared Document Observations, and Evidence Levels](docs/adr/0002-zwergenbrigade-domains-shared-document-and-evidence-levels.md)
- [ADR 0010: Terminal User Interface and Presentation Architecture](docs/adr/0010-terminal-user-interface-and-presentation-architecture.md)
- [ADR 0011: Diagnostic Event Model and Event Transport](docs/adr/0011-diagnostic-event-model-and-event-transport.md)
- [ADR 0012: TUI Application State and Asynchronous Execution](docs/adr/0012-tui-application-state-and-asynchronous-execution.md)
- [ADR 0013: Investigation Workbench Information Architecture](docs/adr/0013-investigation-workbench-information-architecture.md)
- [ADR 0014: Evidence Presentation and Epistemic Integrity](docs/adr/0014-evidence-presentation-and-epistemic-integrity.md)
- [ADR 0015: TUI Visual Language and Terminal Accessibility](docs/adr/0015-tui-visual-language-and-terminal-accessibility.md)
- [Die Zwergenbrigade](docs/architecture/zwergenbrigade.md)
- [Shared Document Analysis](docs/architecture/document-analysis.md)
- [Engineering & Git Conventions](docs/conventions.md)
- [Agent Guidelines](AGENTS.md)

## License

MIT — see [LICENSE](LICENSE).

### Compare rendered text across saved audits

Run two browser-enabled checks against the same page and save each result.
`diff` accepts JSON reports or the latest entry from each JSONL history file.

```sh
nzw check https://example.org/ --browser --history baseline.jsonl
nzw check https://example.org/ --browser --history current.jsonl
nzw diff baseline.jsonl current.jsonl
nzw diff baseline.jsonl current.jsonl --format json
```

The comparison reports changed, unchanged and incomparable baseline blocks.
Older reports without rendered comparison evidence give an unavailable result.
The diff reads the saved files locally.
