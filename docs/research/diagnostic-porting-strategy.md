# Diagnostic Porting Strategy

How NetzZwergenWacht ports diagnostic capabilities from SquirrelScan (`640f9b36afc467f83ab9ebf5890bf4ac8ae6bdaf`, MIT) into idiomatic Rust.

## Core Principles

1. **Adapt, do not clone:** Preserve NZW's `EvidenceSnapshot`, `DocumentObservations`, `AnalyserResult`, `EvidenceRef`, and `Die Zwergenbrigade` architecture.
2. **Observation-first:** Never parse HTML or fetch URLs per rule. Extend `DocumentObservations` or `HttpEvidence` once, then evaluate all dependent rules in memory.
3. **Strict licence hygiene:** Retain attribution in `THIRD_PARTY_NOTICES.md` and `docs/research/diagnostic-capability-mapping.json`. Never reuse upstream trademarks (`TRADEMARKS.md`) or cloud-only services.
4. **Native Rust by default:** Pure deterministic rules live in `src/analysis/*.rs`. Only browser rendering (`chromium`), rendered WCAG (`axe-core`), and laboratory CWV (`lighthouse`) remain optional external instruments behind `CollectorOutcome`.
5. **No synthetic passes:** Missing or truncated evidence yields `CheckStatus::Skipped` or `CheckStatus::Unavailable`, never `Passed` or `0`.

## Porting Workflow per Rule Family

1. Inspect upstream rule implementation and tests in `/tmp/squirrelscan-ref/packages/rules/src/<category>/`.
2. Verify required observations exist in `DocumentObservations` / `HttpEvidence` / `BrowserEvidence`.
3. Define stable canonical `RuleId`s under the appropriate dwarf module (`seo.*`, `sec.*`, `net.*`, `perf.*`, `sem.*`, `a11y.*`, `content.*`, `visual.*`, `browser.*`).
4. Implement deterministic evaluation with `EvidenceRef` provenance and en-GB messages.
5. Add unit tests (positive, negative, edge cases, truncated/missing evidence) and differential fixture tests.
6. Update `docs/research/nzw-rule-inventory.json` and `docs/research/diagnostic-capability-mapping.json`.
