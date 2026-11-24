# Diagnostic Instrument Inventory

External and internal instruments available to Die Zwergenbrigade.

| Instrument | Type | Adapter / Module | Purpose | Evidence Level | Failure Semantics |
| --- | --- | --- | --- | --- | --- |
| `reqwest` + `rustls` | Native Rust | `src/collection.rs` | Bounded HTTP/TLS collection, redirects, headers, body capture | `Source` (Level 1) | `CollectorOutcome::Failed` / `Partial` |
| `scraper` (html5ever) | Native Rust | `src/analysis/document.rs` | Single-pass HTML5 DOM observation extraction | `Source` (Level 1) | Skips doc rules on truncated body |
| Chromium CDP harness | External subprocess | `src/adapters/browser.rs` | Console errors, failed subresources, viewport overflow, broken images | `Runtime` (Level 2) | `CollectorOutcome::Failed` / `Skipped` |
| `@axe-core/cli` (`axe`) | External subprocess | `src/adapters/axe.rs` | Rendered DOM WCAG rule evaluation | `Rendered` (Level 2) | `CollectorOutcome::Failed` / `Skipped` |
| `lighthouse` | External subprocess | `src/adapters/lighthouse.rs` | Laboratory Core Web Vitals (`LCP`, `CLS`, `TBT`) | `Runtime` (Level 2) | `CollectorOutcome::Failed` / `Skipped` |
| `squirrelscan` (optional) | External CLI (MIT) | Planned (`Slice 5`) | Optional cross-check & differential benchmark oracle (`squirrel audit -f json`) | `External` | `CollectorOutcome::Failed` / `Skipped` |
