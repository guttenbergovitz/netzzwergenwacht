# Analysis Engine (`src/analysis/`)

> **Status**: Implemented for Phase 1 Level 1 (Source) deterministic analysers.

The **Analysis Engine** runs independent, deterministic analysers (**Die Zwergenbrigade**) over a shared `EvidenceSnapshot` and shared `DocumentObservations` (`src/analysis/document.rs`).

## 1. Design Rules

- **No Direct Network I/O**: Analysers are pure functions over `&EvidenceSnapshot` (or `&DocumentObservations`) and never spawn HTTP clients or browser processes.
- **Single Normalised Output**: Every analyser emits `AnalyserResult` (`dwarf_id`, `Vec<Finding>`, `Vec<CheckStatus>`).
- **Absence & Truncation Guardrails**: If `snapshot.http` is `Failed`/`Skipped`, HTTP-dependent rules emit `CheckStatus::Skipped`. If `HttpEvidence::body_truncated` is `true`, full-document HTML rules emit `CheckStatus::Skipped` to avoid false absence findings.
- **Evidence Capability Levels**: Rules declare their `EvidenceLevel` (`Source`, `Rendered`, `Behavioural`). Higher-level checks (e.g. Core Web Vitals, axe-core, keyboard navigation, `BrowserZwerg`) explicitly emit `CheckStatus::Unavailable` or `CheckStatus::Skipped` in Phase 1.

## 2. Phase 1 Analyser Modules

| Technical Module | Zwerg Identity | Owned Rules / Scope |
|---|---|---|
| `analysis::network` | **NetzZwerg** | HTTP status errors (`4xx`/`5xx`), redirect chain length |
| `analysis::security` | **SicherheitsZwerg** | HTTPS usage, HSTS (`max-age > 0`), CSP (`unsafe-inline`/`unsafe-eval`), `X-Content-Type-Options`, `X-Frame-Options` / `frame-ancestors`, `Referrer-Policy` |
| `analysis::performance` | **LeistungsZwerg** | HTTP exchange duration, payload size, compression, cache headers; Level 2 Core Web Vitals (`LCP`, `CLS`) from `LighthouseMetrics` (or `Unavailable` when uncollected) |
| `analysis::semantics` | **StrukturZwerg** | Duplicate IDs, heading hierarchy, landmarks, native interactive semantics, context-aware container ratio |
| `analysis::accessibility` | **ZugänglichkeitsZwerg** | `<html lang>`, `img[alt]`, form labels, broken ARIA ID refs, accessible names, Level 2 `axe-core` violations; marks Behavioural `Unavailable` |
| `analysis::seo` | **SuchZwerg** | `<title>`, meta description, canonical URL, `robots` / `X-Robots-Tag` `noindex` |
| `analysis::content` | **InhaltsZwerg** | Word count, text-to-HTML ratio, reading ease |
| `analysis::browser` | **BrowserZwerg** | Console error events and failed subresource requests over `BrowserEvidence` (or `Skipped` when uncollected) |
| `analysis::visual` | **GestaltungsZwerg** | Per-viewport horizontal overflow and broken rendered images (`naturalWidth == 0`) over `BrowserEvidence` (or `Skipped` when uncollected) |

Note: Automated accessibility checks in `ZugänglichkeitsZwerg` report machine-verifiable issues only and never claim full WCAG or EU Accessibility Act legal compliance.
