# SquirrelScan Upstream Reference Manifest

- **Repository URL:** `https://github.com/squirrelscan/squirrelscan`
- **Default branch:** `main`
- **Pinned commit SHA:** `640f9b36afc467f83ab9ebf5890bf4ac8ae6bdaf`
- **Latest release tag / changelog entry:** `v0.0.191-beta.1` (`2026-11-23`)
- **Retrieval date:** `2026-11-25`
- **Primary licence:** MIT License (`LICENSE`, Copyright (c) 2026 squirrelscan)

## Package-Level Licence Verification

Verified across `apps/cli/package.json` and all 17 workspace packages under `packages/*/package.json`:

- `apps/cli`, `packages/api-client`, `packages/audit-engine`, `packages/cloud-client`, `packages/config`, `packages/core-contracts`, `packages/crawler`, `packages/fetchers`, `packages/page-classifier`, `packages/parser`, `packages/report`, `packages/rules`, `packages/synthetic-site`, `packages/tech-detect`, `packages/threat-intel`, `packages/tls-probe`, `packages/utils`, `packages/waf-detect` — all declare `"license": "MIT"`.
- `TRADEMARKS.md` explicitly states that the MIT Licence covers the software, **not** SquirrelScan names, logos, icons, or brand identifiers. NZW must retain its own branding and never imply endorsement.

## Relevant Source Paths

- `packages/rules/src/` — 360 rule definitions across 23 categories (`a11y`, `analytics`, `ax`, `blocking`, `content`, `core`, `crawl`, `eeat`, `gaps`, `i18n`, `images`, `integrity`, `legal`, `links`, `local`, `mobile`, `perf`, `reliability`, `schema`, `security`, `social`, `url`, `video`), rule runner (`runner.ts`), applicability (`applicability.ts`), and cloud plumbing (`cloud.ts`).
- `packages/crawler/` — frontier management, robots/sitemap parsing, and rate-limited crawling.
- `packages/parser/` — HTML/DOM extraction feeding `RuleContext.parsed`.
- `packages/audit-engine/` — orchestration and prefetching.
- `packages/rules/tests/` — rule test suites and fixtures.

## Local vs Cloud-Only Split

- **346 rules** execute locally against fetched HTML, HTTP headers, TLS probes, or browser/crawler state.
- **14 rules** declare a `cloud` spec (`packages/rules/src/cloud.ts`) backed by SquirrelScan's credit-gated `/v1/services/*` backend (`not-authenticated`, `insufficient-credits`). Cloud-only rules are classified as `cloud_only_or_unavailable` in NZW's mapping.

## Known Limitations

- Upstream is TypeScript/Bun-based; NZW ports diagnostic intent and algorithms into idiomatic Rust without adding Bun/Node.js as a runtime dependency for deterministic rules.
- Some upstream rules depend on cloud prefetch or external browser rendering; NZW preserves explicit `CollectorOutcome` / `Measurement<T>` semantics when evidence is absent.
