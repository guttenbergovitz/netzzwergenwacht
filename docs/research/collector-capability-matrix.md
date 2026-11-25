# Collector Capability Matrix

Inventory of NetzZwergenWacht data collectors, evidence levels, resource budgets, and completeness guarantees.

| Collector | Module | Evidence Level | Default Bounds / Sampling Caps | Truncation / Partial Semantics |
| --- | --- | --- | --- | --- |
| HTTP Collector | `collection::http` | `Source` | `ExecutionBudget` timeout, redirect limit, `max_response_bytes` | `body_truncated` -> `CollectorOutcome::Partial` |
| TLS Inspector | `collection::tls` | `Source` | `ExecutionBudget` timeout | Missing/unverified TLS -> `Skipped` or `Failed` |
| HTML5 Observation Parser | `analysis::document` | `Source` | Single HTML5 parse pass (`visible_text_sample` 4096 B) | Skipped on missing/truncated HTML |
| Discovery & Sitemap Crawler | `discovery` | `Source` | `CrawlBudget` (`max_pages`, `max_depth`, same-origin) | Records `coverage_complete` in `ApplicationGraph` |
| Chromium CDP Harness | `adapters::browser` | `Rendered` | `resources` <= 200, `rendered_images` <= 100, `ax_tree` <= 5000 nodes, 15s load timeout | `load_timed_out` / truncation flags -> `CollectorOutcome::Partial` |
| `axe-core` Adapter | `adapters::axe` | `Rendered` | External CLI invocation bounded by timeout | `Unavailable` when Chromium/axe absent |
| Lighthouse Adapter | `adapters::lighthouse` | `Rendered` | External CLI invocation bounded by timeout | `Unavailable` when Lighthouse absent |
| Source Content Segmentation | `analysis::segmentation` | `Source` | Complete HTTP HTML, 32,768 nodes, depth 128, 256 paragraphs, 4 KiB per paragraph, 128 bytes per language attribute | Tree and paragraph limits explicit. A missing or ambiguous main landmark leaves word distribution unavailable. |
| Browser Runtime and Network Timeline | `adapters::browser` | `Rendered` | Existing Chromium session, 512 events, 128-byte identifier fields, 16 events per query | Explicit event cap and load termination, optional timestamps and correlation. Older snapshots have no timeline. |
| Rendered DOM Segmentation | `adapters::browser` | `Rendered` | Main-frame light DOM at the desktop viewport, 16,384 node visits, depth 64, 256 blocks, 512 UTF-16 units per excerpt. Identity census adds up to 16,384 node visits and counts IDs of up to 128 UTF-16 units | Explicit traversal, retention and census limits. Complete CSS-visible text can carry a versioned fingerprint. Failed evaluation is unavailable. |
