# NetzZwergenWacht

[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Evidence-driven external web quality and reliability auditing engine with optional AI-assisted analysis.**
>
> **Die Zwergenbrigade** — *Kleine Zwerge. Große Sorgfalt.* (*Small dwarfs. Great diligence.*)

NetzZwergenWacht (NZW) is being redesigned and rewritten in Rust on the `rewrite/rust` branch. The original Python prototype is preserved on `main` and in [`legacy/`](legacy/README.md) as a frozen historical reference.

## Current Status (`Phase 1–4 Complete`)

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
  - Optional `KommandantZwerg` AI synthesis (`src/intelligence/`, opt-in `--ai`, `LlmBudget` caps, `<untrusted_audit_evidence>` prompt-injection boundaries).
  - **DokumentationsZwerg** CLI (`nzw check`, `nzw batch`, `nzw diff`, `nzw validate`) with plain-text and versioned JSON output, TOML config/policy gates (`--config`, `--fail-on`), JSONL history (`--history`), and exit codes (`0` clean, `1` findings/partial, `2` input/collection failure).
- **Planned (Phase 5)**:
  - Production hardening: chaos/cancellation tests, `tracing` / OpenTelemetry observability, benchmarks, and release packaging.

See [docs/roadmap.md](docs/roadmap.md) for the full roadmap.

## Usage

```bash
# Run deterministic audit (text output)
cargo run --locked -- check https://example.org

# Run deterministic audit (versioned JSON output)
cargo run --locked -- check https://example.org --format json

# Validate target URL and SSRF policy without fetching
cargo run --locked -- validate https://example.org
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

- [ADR 0001: Rewrite NetzZwergenWacht in Rust](docs/adr/0001-rewrite-netzzwergenwacht-in-rust.md)
- [ADR 0002: Zwergenbrigade Domains, Shared Document Observations, and Evidence Levels](docs/adr/0002-zwergenbrigade-domains-shared-document-and-evidence-levels.md)
- [Die Zwergenbrigade](docs/architecture/zwergenbrigade.md)
- [Shared Document Analysis](docs/architecture/document-analysis.md)
- [Engineering & Git Conventions](docs/conventions.md)
- [Agent Guidelines](AGENTS.md)

## License

MIT — see [LICENSE](LICENSE).
