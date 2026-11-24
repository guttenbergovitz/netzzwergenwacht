# Analysis Engine

> **Status**: Target Design (Phase 1 basic deterministic rules; Phase 2 full domain analysers).

The **Analysis Engine** runs independent, deterministic analysers ("Zwerge") over a shared `EvidenceSnapshot`.

## 1. Design Rules

- **No Direct Network I/O**: Analysers receive `&EvidenceSnapshot` and `&AuditConfig`; they must not spawn HTTP clients or browser processes.
- **Single Normalised Output**: No split between `analyze()` and `analyze_detailed()`. Every analyser emits `AnalyserResult` containing `Vec<Finding>`, typed domain `Measurement`s, and `CheckStatus` records.
- **Absence of Evidence**: If required evidence in `EvidenceSnapshot` is `Failed` or `Skipped`, the analyser emits `CheckStatus::Skipped` / `Unavailable` instead of false-positive or false-negative findings.
- **Rule Versioning**: Every rule carries a `RuleId` and `RuleVersion` so findings remain reproducible across engine upgrades.

## 2. Target Analyser Domains

| Domain | Zwerg Identity | Primary Evidence Consumed |
|---|---|---|
| Web Reliability | `WebBrowserZwerg` | HTTP status, redirects, console/network errors |
| Security Posture | `SicherheitsZwerg` | TLS metadata, HTTP security headers, cookies |
| Performance | `LeistungsZwerg` | Lighthouse adapter output, resource sizes, compression/cache headers |
| Accessibility | `ZugaenglichkeitsZwerg` | axe-core adapter output, semantic/ARIA/viewport evidence |
| SEO | `SEOZwerg` | HTML/DOM head tags, canonical, robots/sitemap, JSON-LD |
| Content Quality | `InhaltZwerg` | Extracted DOM text, headings, freshness headers |
| Visual Integrity | `VisualZwerg` | Viewport overflow, broken images, responsive screenshots |

Note: Automated accessibility checks in `ZugaenglichkeitsZwerg` report machine-verifiable issues only and never claim full WCAG or EU Accessibility Act legal compliance.
